array = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
found = False
first = 0
last = (len(array) - 1)
searchItem = 4

while not found:
    if found:
        break

    elif not found:
        midPoint = ((first-last)/2)
        midPoint = round(midPoint)
        if array[midPoint] == searchItem:
            print("Item found at index", midPoint)
            found = True

        elif first >= last:
            print("Item not found")
            break

        if array[midPoint] > searchItem:
            last = midPoint-1

        else:
            last = midPoint+1