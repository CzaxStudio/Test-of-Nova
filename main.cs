/* 
   A comprehensive C# script for a Weather Data CLI.
   Requires: Newtonsoft.Json (via NuGet or #r directive)
*/

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Newtonsoft.Json;

// 1. Define Data Models
public class WeatherReport {
    public string City { get; set; }
    public double Temperature { get; set; }
    public string Condition { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.Now;
}

// 2. Constants and Configuration
const string LogFile = "weather_log.json";
string[] targetCities = { "New York", "London", "Tokyo", "Berlin" };

// 3. Execution Logic (Top-level statements)
Console.WriteLine("--- Starting Weather Data Collector ---");

try {
    var reports = await FetchWeatherDataAsync(targetCities);
    
    // Process and display data using LINQ
    var averageTemp = reports.Average(r => r.Temperature);
    Console.WriteLine($"\nAverage Temp: {averageTemp:F2}°C");
    
    foreach (var report in reports.OrderByDescending(r => r.Temperature)) {
        Console.WriteLine($"[{report.Timestamp:HH:mm}] {report.City}: {report.Temperature}°C ({report.Condition})");
    }

    // Save results to a local file
    await SaveReportsAsync(reports);
}
catch (Exception ex) {
    Console.ForegroundColor = ConsoleColor.Red;
    Console.WriteLine($"Critical Error: {ex.Message}");
    Console.ResetColor();
}

// 4. Helper Methods
async Task<List<WeatherReport>> FetchWeatherDataAsync(string[] cities) {
    using var client = new HttpClient();
    var results = new List<WeatherReport>();

    foreach (var city in cities) {
        Console.Write($"Fetching {city}...");
        // Mocking an API call for this example
        await Task.Delay(500); 
        
        results.Add(new WeatherReport {
            City = city,
            Temperature = new Random().Next(-10, 35),
            Condition = "Sunny"
        });
        Console.WriteLine(" Done.");
    }
    return results;
}

async Task SaveReportsAsync(List<WeatherReport> reports) {
    string json = JsonConvert.SerializeObject(reports, Formatting.Indented);
    await File.AppendAllTextAsync(LogFile, json + Environment.NewLine);
    Console.WriteLine($"\nSuccess: Reports saved to {Path.GetFullPath(LogFile)}");
}
