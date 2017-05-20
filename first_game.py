#!/usr/bin/env python
import random
print("""This program lets you choose the operand you want to use.
But the funny thing here is that the computer chooses the numbers :))
Try and guess if the first number is 'GREATER_THAN' or 'LESS_THAN' the second number.
If you get three True statements on row you can call yourself a winner!
This is a very simple game and is not jet able to keep score.
The random numbers will be between 1 and 100, making it a bit difficult.
GOOD LUCK!\n""")

a = random.randrange(1, 100)
b = random.randrange(1, 100)
print("Is A greater_than or less_than B?\n")
i = input("Enter a operand: ")
print(a, i, b)
try:
    if i == '>':
        try:
            if a > b:
                print("You used the greater than operand")
        finally:
            print(a > b)
    elif i == '<':
        try:
            if a < b:
                print("You used the less than operand")
        finally:
            print(a < b)
    else:
        print("Unknown operand")
finally:
    print("\nPlease try again")
    
input("Press enter to exit.")
