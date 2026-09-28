import torch
import numpy as np
from sklearn.isotonic import IsotonicRegression

def fix_ece():
    print("Fixing ECE natively in benchmark...")
