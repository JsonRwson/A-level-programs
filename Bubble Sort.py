numbersList = [1, 4, 2, 17, 19, 20, 21, 39, 1, 2, 4]

def bubbleSort(data):
    has_swapped = True
    while has_swapped:
        has_swapped = False
        for x in range(0, len(data)-1):
            if data[x] > data[x+1]:
                temp = data[x]
                data[x] = data[x+1]
                data[x+1] = temp
                has_swapped = True
        print(data)

bubbleSort(numbersList) 