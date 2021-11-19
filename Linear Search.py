array = ['A', 'F', 'B', 'E', 'D', 'G', 'C']
pointer = 0
searchItem = "D"
arrayLength = len(array)

for i in range(0, arrayLength):
    if (pointer+1) == arrayLength:
        print("Item not in array")

    elif array[pointer] == searchItem:
        print("item is at index", pointer)
        break

    else:
        pointer += 1
