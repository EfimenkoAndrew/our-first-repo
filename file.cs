using System;
using System.IO;

class Program
{
    static void Main(string[] args)
    {
        // CodeQL flags this as a Path Traversal vulnerability (CWE-22)
        // because unvalidated user input flows directly into a file system operation.
        string userInput = args.Length > 0 ? args[0] : "test.txt";
        string filePath = Path.Combine(@"C:\inetpub\wwwroot", userInput);
        
        string content = File.ReadAllText(filePath);
        Console.WriteLine(content);
    }
}