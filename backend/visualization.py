import matplotlib.pyplot as plt
import numpy as np

import numpy as np
import matplotlib.pyplot as plt

categories = ['/decrypt', '/encrypt', '/login']
average_times = [4, 2383, 259] 
min_times = [3, 4, 229] 
max_times = [5, 4271, 302] 

x = np.arange(len(categories)) 
width = 0.25  

plt.figure(figsize=(10, 6))
bars1 = plt.bar(x - width, average_times, width, label='Ortalama', color='skyblue')
bars2 = plt.bar(x, min_times, width, label='Minimum', color='lightgreen')
bars3 = plt.bar(x + width, max_times, width, label='Maksimum', color='salmon')

for bar in bars1:
    plt.text(bar.get_x() + bar.get_width() / 2, bar.get_height(), f'{bar.get_height():.0f}', ha='center', va='bottom', fontsize=9)
for bar in bars2:
    plt.text(bar.get_x() + bar.get_width() / 2, bar.get_height(), f'{bar.get_height():.0f}', ha='center', va='bottom', fontsize=9)
for bar in bars3:
    plt.text(bar.get_x() + bar.get_width() / 2, bar.get_height(), f'{bar.get_height():.0f}', ha='center', va='bottom', fontsize=9)

plt.xlabel('İstek Türleri')
plt.ylabel('Süre (ms)')
plt.title('Algoritma Karşılaştırmaları (Değerlerle)')
plt.xticks(x, categories)
plt.legend()
plt.show()


algorithms = ['AES', 'Blowfish', 'ChaCha20', 'ECIES']
data_sizes = ['SMALL', 'MEDIUM', 'LARGE', 'XLARGE']
encrypt_times = [
    [4261.02, 3338.8, 8881.44, 25350.81],  # AES
    [2395.11, 3481.03, 8860.94, 24911.22],  # Blowfish
    [2477.8, 3342.76, 8523.41, 24769.77],  # ChaCha20
    [2398.75, 2503.28, 8296.1, 27671.4]   # ECIES
]
decrypt_times = [
    [24.59, 15.45, 43.08, 168.72],  # AES
    [26.99, 13.47, 77.39, 196.17],  # Blowfish
    [25.38, 26.5, 48.46, 164.11],  # ChaCha20
    [25.01, 5.62, 52.1, 173.98]    # ECIES
]

x = np.arange(len(data_sizes)) 
bar_width = 0.2  

plt.figure(figsize=(10, 6))
for i, algorithm in enumerate(algorithms):
    plt.bar(x + i * bar_width, [encrypt_times[i][j] for j in range(len(data_sizes))],
            width=bar_width, label=f'{algorithm} Encrypt')

for i, algorithm in enumerate(algorithms):
    plt.bar(x + i * bar_width, [decrypt_times[i][j] for j in range(len(data_sizes))],
            width=bar_width, bottom=[encrypt_times[i][j] for j in range(len(data_sizes))],
            label=f'{algorithm} Decrypt', alpha=0.7)

plt.xlabel('Veri Boyutları')
plt.ylabel('Süre (ms)')
plt.title('Algoritma Performans Karşılaştırması')
plt.xticks(x + bar_width * 1.5, data_sizes)
plt.legend()
plt.show()

import numpy as np

categories = ['/decrypt', '/encrypt', '/login']
average_times = [4, 2383, 259]  # Ortalama yanıt süreleri (ms)
min_times = [3, 4, 229]  # Minimum süreler (ms)
max_times = [5, 4271, 302]  # Maksimum süreler (ms)

x = np.arange(len(categories))  
width = 0.25  

plt.figure(figsize=(10, 6))
plt.bar(x - width, average_times, width, label='Ortalama', color='skyblue')
plt.bar(x, min_times, width, label='Minimum', color='lightgreen')
plt.bar(x + width, max_times, width, label='Maksimum', color='salmon')

plt.xlabel('İstek Türleri')
plt.ylabel('Süre (ms)')
plt.title('Algoritma Karşılaştırmaları')
plt.xticks(x, categories)
plt.legend()
plt.show()

percentiles = ['50%', '66%', '75%', '80%', '90%', '95%', '98%', '99%', '99.9%', '100%']
decrypt_times = [4, 4, 5, 5, 5, 5, 5, 5, 5, 5]
encrypt_times = [2500, 2700, 2800, 3200, 3300, 4200, 4300, 4300, 4300, 4300]
login_times = [250, 280, 280, 300, 300, 300, 300, 300, 300, 300]

plt.figure(figsize=(12, 6))
plt.plot(percentiles, decrypt_times, marker='o', label='/decrypt', color='blue')
plt.plot(percentiles, encrypt_times, marker='s', label='/encrypt', color='green')
plt.plot(percentiles, login_times, marker='^', label='/login', color='orange')

plt.ylabel('Yanıt Süresi (ms)')
plt.title('Yanıt Süresi Dağılımı')
plt.legend()
plt.grid(True)
plt.show()
