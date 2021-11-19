queue = [34, 54, 22, 32]

front_pointer = 0
rear_pointer = 3

if front_pointer == rear_pointer:
    print("Queue is empty")
else:
    del queue[front_pointer]
    front_pointer += 1

print(queue)
print(front_pointer)

