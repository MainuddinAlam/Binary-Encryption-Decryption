#Encrypt_Decrypt.py
#Solution for Question 3 of Assignment 6
#Author: Mainuddin Alam Irteja
#A#: A00446752

#Imported modules
import sys

#Constants for the program
MAX_PRINTABLE_ASCII_VAL = 127
MIN_PRINTABLE_ASCII_VAL = 32
DIGITS_FOR_BINARY = 7

def encrypt_file(givenStr: str, kVal : int):
    """
    Function to encrypt a file.

    Args:
        givenStr: The string with the information of the
                  input file
        kVal: The key value which is used to shift characters
    Returns:
        encryptedStr: Returns the encrypted string
    """
    #Initialize empty string
    encryptedStr = ""
    #Loop throughe every character in the string
    for aChar in givenStr:
        #Get the ascii value of the current character
        asciiVal = ord(aChar)
        #Shift the value of the ascii character
        newCharVal = asciiVal + kVal
        #Check if newCharVal is greater than MAX_PRINTABLE_ASCII_VAL
        if (newCharVal > MAX_PRINTABLE_ASCII_VAL):
            #Compute the newCharVal if condition is true
            newCharVal = (newCharVal - MAX_PRINTABLE_ASCII_VAL - 1) + MIN_PRINTABLE_ASCII_VAL
        #Get the binary of newCharVal
        binStr = bin(newCharVal)[2:]
        #Place zeros infront of binStr if len(binStr) is not
        #equal DIGITS_FOR_BINARY
        if (len(binStr) != DIGITS_FOR_BINARY):
            numZeros = DIGITS_FOR_BINARY - len(binStr)
            tempStr = binStr
            binStr = "0" * numZeros
            binStr += tempStr

        #Add the current binStr to encryptedStr
        encryptedStr += binStr
    #Return encryptedStr
    return encryptedStr

        

def decrypt_file(givenStr : str, kVal : int):
   """
   Function to decrypt an encrypted file.

   Args:
       givenStr: The string with the information of the
                  input file
       kVal: The key value which is used to shift characters
   Returns:
        encryptedStr: Returns the decrypted string
   """
   #Initialize the decryptedStr, binaryCounter and
   #singleBinRepresentation
   decryptedStr = ""
   binaryCounter = 0
   singleBinRepresentation = ""
   #Loop through every character in the givenStr
   for aChar in givenStr:
       #Add the current character to singleBinRepresentation
       singleBinRepresentation += aChar
       #Increment binaryCounter
       binaryCounter += 1
       #Check if binaryCounter is equal to DIGITS_FOR_BINARY
       if (binaryCounter == DIGITS_FOR_BINARY):
           #Get the asciiVal of the singleBinRepresentation
           asciiVal = int(singleBinRepresentation, 2)
           #Shift the origCharVal
           origCharVal = asciiVal - kVal
           #Check if origCharVal is less than 0
           if (origCharVal < 0):
               #Compute the new origCharVal if condition is true
               origCharVal = origCharVal + MAX_PRINTABLE_ASCII_VAL - 1 - MIN_PRINTABLE_ASCII_VAL 
           #Cast origCharVal to a character and add it
           #to decrypedStr
           decryptedStr += chr(origCharVal)
           #Set singleBinRepresentation and binaryCounter to
           #empty and 0 respectively
           singleBinRepresentation = ""
           binaryCounter = 0
   #Return the decryptedStr
   return decryptedStr   
    

def write_file(givenStr : str, outFileName : str) -> None:
    """
    Function to write to the output file

    Args:
        givenStr: The string with the information of the
                  input file
        outFileName: The name of the output file
    """
    #Write the results to the output file
    outFileName = open(outFileName, "w")
    for aChar in givenStr:
        outFileName.write(aChar)
    outFileName.close()


#get the name of the input file
inFileName = sys.argv[1]
#get whether to encrypt or decrypt
encDec = sys.argv[2]
#get the key value
keyVal = int(sys.argv[3])

#read the plain text file
inFile = open(inFileName, "r")
inFileStr = inFile.read()
inFile.close() #close the input string  

#Encrypt the file
if (encDec == "encrypt"):
    #Get the encrypted binary string
    encryptStr = encrypt_file(inFileStr, keyVal)
    #Set the name of the output file
    outputFileName = "Binary.txt"
    #Write the binary string to the output file, Binary.txt
    write_file(encryptStr, outputFileName)
    #Display to the user that the input file has been encrypted
    print("\nThe input file {0} has been encrypted and has been written to {1}".format(inFileName, outputFileName))
#Decrypt the file
elif (encDec == "decrypt"):
    #Get the decrypted string
    decryptStr = decrypt_file(inFileStr, keyVal)
    #Set the name of the output file
    outputFileName = "Decrypted.txt"
    #Write the decrypted string to the output file, Decrypted.txt
    write_file(decryptStr, outputFileName)
    #Display to the user that the input file has been encrypted
    print("\nThe input file {0} has been encrypted and has been written to {1}".format(inFileName, outputFileName))
#Exit the program
else:
    print("\nIllegal input: {0}.".format(encDec))
    print("Program quitting.")
    exit()


