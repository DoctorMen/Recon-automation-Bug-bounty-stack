import time
import matplotlib.pyplot as plt

# Simulated benchmark data
manual_times = [120, 150, 180, 200, 240]  # in seconds
automated_times = [24, 30, 36, 40, 48]  # 5x faster

# Calculate ROI
cost_manual = 1000  # Hypothetical cost for manual testing
cost_automated = 200  # Hypothetical cost for automated testing
roi = ((cost_manual - cost_automated) / cost_automated) * 100

# Plot benchmark results
def plot_benchmarks():
    labels = ['Test 1', 'Test 2', 'Test 3', 'Test 4', 'Test 5']
    x = range(len(labels))

    plt.figure(figsize=(10, 6))
    plt.bar(x, manual_times, width=0.4, label='Manual Testing', color='red', align='center')
    plt.bar(x, automated_times, width=0.4, label='Automated Testing', color='green', align='edge')

    plt.xlabel('Test Cases')
    plt.ylabel('Time (seconds)')
    plt.title('Performance Benchmark: Manual vs Automated Testing')
    plt.xticks(x, labels)
    plt.legend()
    plt.tight_layout()
    plt.savefig('benchmark_results.png')
    plt.show()

if __name__ == "__main__":
    start_time = time.time()
    plot_benchmarks()
    end_time = time.time()
    print(f"Benchmark completed in {end_time - start_time:.2f} seconds")
    print(f"ROI of automation: {roi:.2f}%")
