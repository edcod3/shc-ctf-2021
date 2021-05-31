#Import Z3 SMT 
from z3 import *

#Define variables
#a = Real('a')
#b = Real('b')
#c = Real('c')
#d = Real('d')

a, b, c, d = Ints('a b c d')

#Create the solver
s = Solver()

s.add(a > 400000)
s.add(a % 30 == 5)
s.add(b > 30000000000000000)
s.add(a**2 < b)
s.add(b % 2400000000000000 == 3)
s.add(2*(a+b) == c+(d*100))
s.add(d > 40000000000)
s.add((d*25)% 4 == 1)
s.add(d % 99 == 3)
s.add(d % 5 == 1)

print(s.check())
print(s.model())