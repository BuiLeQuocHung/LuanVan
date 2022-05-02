


def find(mang): 
    result_idx = None
    biggest_gap = 0

    start_idx = 0
    stop_idx = 1

    for i in range(1, len(mang)):
        if mang[i] < mang[i - 1]:
            if stop_idx - start_idx > biggest_gap:
                result_idx = [start_idx, stop_idx - 1]
                biggest_gap = stop_idx - start_idx
            start_idx = stop_idx  
        
        stop_idx += 1

    if stop_idx - start_idx > biggest_gap:
        result_idx = [start_idx, stop_idx - 1]

    return result_idx

print(find([0,0,0,0,1,0,0,0,0,0,1]))
