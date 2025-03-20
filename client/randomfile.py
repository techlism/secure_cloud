import random

file1 = open("test.txt","a") 
PsudoRandomWords = ["Apple ", "Banana ", "Tree ", "Pickle ", "Toothpick ", "Coffee ", "Done "]

index = 0
#Increase the range to make a bigger file
for x in range(150000000):
   #Change end range of the randint function below if you add more words
   index = random.randint(0,6)
   file1.write(PsudoRandomWords[index])
   if x % 20 == 0:
      file1.write('\n')