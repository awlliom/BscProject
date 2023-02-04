# BscProject
This my project for BSc in Computer Engineering in Isfahan University of Technology.
The purpose of this project is to do an empirical analysis of smart contract testing tools. Its output would be like this:


# Accuracy

|  Category           | Confuzzius  |   Conkas    |  Manticore  |   Mythril   |   Slither   |    Total    |
| ------------------- | ----------- | ----------- | ----------- | ----------- | ----------- | ----------- |
| Access Control      |    2/6  33% |    0/6   0% |    0/6   0% |    2/6  33% |    1/6  17% |   3/ 6  50% |
| Arithmetic          |    3/7  43% |    2/7  29% |    1/7  14% |    3/7  43% |    0/7   0% |   4/ 7  57% |
| Bad Randomness      |    0/7   0% |    0/7   0% |    0/7   0% |    0/7   0% |    0/7   0% |   0/ 7   0% |
| Denial Of Service   |    0/3   0% |    0/3   0% |    0/3   0% |    0/3   0% |    0/3   0% |   0/ 3   0% |
| Front Running       |    0/3   0% |    1/3  33% |    0/3   0% |    0/3   0% |    0/3   0% |   1/ 3  33% |
| Other               |    0/1   0% |    0/1   0% |    0/1   0% |    0/1   0% |    1/1 100% |   1/ 1 100% |
| Reentrancy          |    2/2 100% |    2/2 100% |    0/2   0% |    0/2   0% |    2/2 100% |   4/ 2 200% |
| Time Manipulation   |    0/2   0% |    1/2  50% |    1/2  50% |    0/2   0% |    1/2  50% |   2/ 2 100% |
| Unchecked Calls     |    1/4  25% |    2/4  50% |    0/4   0% |    1/4  25% |    0/4   0% |   3/ 4  75% |
| Total               |   8/36  22% |   8/36  22% |   2/36   6% |   6/36  17% |   5/36  14% |  18/36  50% |

# Combine tools 
|             | Confuzzius  |   Conkas    |  Manticore  |   Mythril   |   Slither   |
| ----------- | ----------- | ----------- | ----------- | ----------- | ----------- |
| Confuzzius  |             | 13/36   36% | 10/36   28% | 9/36    25% | 10/36   28% |
| Conkas      |             |             | 8/36    22% | 12/36   33% | 10/36   28% |
| Manticore   |             |             |             | 7/36    19% | 6/36    17% |
| Mythril     |             |             |             |             | 10/36   28% |
| Slither     |             |             |             |             |             |
