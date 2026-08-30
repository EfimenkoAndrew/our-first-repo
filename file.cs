using Microsoft.AspNetCore.Mvc;
using System.Data.SqlClient;

[ApiController]
[Route("[controller]")]
public class UserController : ControllerBase
{
    [HttpGet("search")]
    public IActionResult Search(string username)
    {
        // CodeQL tracks untrusted 'username' from the HTTP request source 
        // directly into the SqlCommand string concatenation sink (SQL Injection).
        string connectionString = "Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password=myPassword;";
        
        using (var connection = new SqlConnection(connectionString))
        {
            connection.Open();
            string query = "SELECT * FROM Users WHERE Username = '" + username + "'";
            
            using (var command = new SqlCommand(query, connection))
            {
                using (var reader = command.ExecuteReader())
                {
                    // Execution
                }
            }
        }
        
        return Ok("Search completed.");
    }
}
