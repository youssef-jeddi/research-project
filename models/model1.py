import torch.nn as nn


class SmallMLP(nn.Module):
    def __init__(self):
        super().__init__()
        self.layers = nn.Sequential(
            nn.Linear(4, 16),
            nn.ReLU(),
            nn.Linear(16, 8),
            nn.ReLU(),
            nn.Linear(8, 2),
        )

    def forward(self, x):
        return self.layers(x)


Model = SmallMLP
INPUT_SHAPE = (1, 4)
DESCRIPTION = "3-layer MLP (4 -> 16 -> 8 -> 2)"
