import json
import numpy as np
import matplotlib.pyplot as plt
from scipy.stats import norm
import os

# Estrazione dei valori
file_path = os.path.join(os.path.dirname(__file__), "1760106275_initiator_classic_post-quantum.json")

# Lettura del file JSON
with open(file_path, "r") as f:
    data = json.load(f)


# Estrazione dei valori di memory_avg
memory_avgs = [run['memory_avg'] for run in data['individual_runs']]
mean_memory = np.mean(memory_avgs)
std_memory = np.std(memory_avgs)


# Istogramma con 10 bin
plt.figure(figsize=(10,6))
plt.hist(memory_avgs, bins=10, color='skyblue', edgecolor='black')

# Linea della media
plt.axvline(mean_memory, color='red', linestyle='dashed', linewidth=2, label=f'Media: {mean_memory:.3f}')

# Linee della deviazione standard
plt.axvline(mean_memory + std_memory, color='green', linestyle='dashed', linewidth=2, label=f'+1σ: {mean_memory + std_memory:.3f}')
plt.axvline(mean_memory - std_memory, color='green', linestyle='dashed', linewidth=2, label=f'-1σ: {mean_memory - std_memory:.3f}')


plt.xlabel('Memory Avg')
plt.ylabel('Numero di esecuzioni')
plt.title('Distribuzione delle Memory Avg')
plt.grid(axis='y')
plt.show()