

#Auxillary functions
def bits_to_bytes(b: list[int]) -> bytes:

    if len(b) % 8 != 0:
        raise ValueError("Bit length must be a multiple of 8.")

    #Initialize the byte array B with zeros
    byte_array = [0] * (len(b) // 8)  # size of byte array is len(bit_array) / 8
    
    #Iterate over each bit in the input bit_array
    for i in range(len(b)):
        # Update the byte in the byte_array corresponding to the bit
        byte_array[i // 8] += b[i] * (2 ** (i % 8))
    
    #Return the resulting byte_array
    return byte_array

def bytes_to_bits(B: list[int]) -> list[int]:
    C = B.copy() 

    bit_array = [0] * (len(C) * 8)

    for i in range(len(C)):
        for j in range(8):
             # Extract the least significant bit (little-endian)
            bit_array[8 * i + j] = C[i] % 2
            
            # Shift the byte to the right for the next bit
            C[i] //= 2

    return bit_array

def main():
    bit = [1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1] 
    print(bits_to_bytes(bit))

    B = [139, 128]  
    print(bytes_to_bits(B))


if __name__ == "__main__":
    main()

