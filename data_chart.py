import matplotlib.pyplot as plt
import numpy as np

# Data
algorithms = [
    'Boyer-Moore', 'KMP', 'Linear Search', 'Rabin-Karp', 
    'Bitap', 'Finite-state Automaton', 'Naïve Search', 'Hybrid Approach'
]
time_true = [0.45, 0.08, 0.05, 0.08, 0.05, 0.3, 0.07, 0.006]
time_false = [0.01, 0.06, 0.01, 0.01, 0.00006, 0.1, 0.04, 0.000]

# Bar width
bar_width = 0.35
index = np.arange(len(algorithms))

# Plot
fig, ax = plt.subplots(figsize=(12, 8))

bars1 = ax.bar(index - bar_width/2, time_true, bar_width, label='REREAD_ON_QUERY = True')
bars2 = ax.bar(index + bar_width/2, time_false, bar_width, label='REREAD_ON_QUERY = False')

# Add labels
ax.set_xlabel('Algorithms')
ax.set_ylabel('Execution Time (seconds)')
ax.set_title('Comparison of File Search Algorithms')
ax.set_xticks(index)
ax.set_xticklabels(algorithms, rotation=45, ha='right')
ax.legend()

# Add value labels
def add_labels(bars):
    for bar in bars:
        height = bar.get_height()
        ax.annotate(f'{height:.3f}',
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3),  # 3 points vertical offset
                    textcoords="offset points",
                    ha='center', va='bottom')

add_labels(bars1)
add_labels(bars2)

plt.tight_layout()
plt.show()
