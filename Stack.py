stack = [13, 23, 21, 43, 32]
topPointer = 4

print("stack before algorithm")
print(stack)

if topPointer == 0:
    print("Stack is empty")
else:
    stack.pop(topPointer)
    topPointer -= 1

print("stack after algorith")
print(stack)