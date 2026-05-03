import sys
import csv
import random

urls = []
weights = []

with open(sys.argv[1], 'r') as csv_file:
    csv_reader = csv.reader(csv_file)

    for row in csv_reader:
        _, url, weight = row
        urls.append(url)
        weight = weight.replace(",","")
        weights.append(float(weight))

wmin = min(weights)
wmax = max(weights)
wrange = wmax - wmin
weights = [((w-wmin)/wrange)+0.1 for w in weights]

samples = random.choices(urls, weights=weights, k=int(sys.argv[3]))

with open(sys.argv[2], 'w') as f:
    for url in samples:
        f.write(f"{url}\n")