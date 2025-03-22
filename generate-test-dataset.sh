#!/bin/bash

# Script to generate a test dataset for performance testing
# This creates a variety of .NET files that will stress different aspects of the scanner

TEST_DIR="./test-dataset"

# Create test directory if it doesn't exist
mkdir -p $TEST_DIR
mkdir -p $TEST_DIR/controllers
mkdir -p $TEST_DIR/models
mkdir -p $TEST_DIR/services
mkdir -p $TEST_DIR/views
mkdir -p $TEST_DIR/config

echo "Generating test dataset in $TEST_DIR..."

# =======================================
# 1. Create vulnerable controller files
# =======================================
for i in {1..10}; do
  cat > $TEST_DIR/controllers/VulnerableController$i.cs << EOF
using System;
using System.Data.SqlClient;
using System.Web.Mvc;

namespace TestProject.Controllers {
    public class VulnerableController$i : Controller {
        private readonly string connectionString = "Server=myserver;Database=mydb;User Id=myuser;Password=mypassword;";
        
        [HttpPost]
        public ActionResult Search(string searchTerm) {
            // SQL Injection vulnerability
            using (var conn = new SqlConnection(connectionString)) {
                conn.Open();
                var cmd = new SqlCommand("SELECT * FROM Products WHERE Name LIKE '%" + searchTerm + "%'", conn);
                var reader = cmd.ExecuteReader();
                // Process results
            }
            
            // XSS vulnerability
            ViewBag.SearchResults = "Results for: " + searchTerm;
            return View();
        }
        
        [HttpPost]
        public ActionResult ProcessForm(string username, string message) {
            // Missing CSRF protection
            
            // XSS vulnerability with direct Response.Write
            Response.Write("<div>" + username + "</div>");
            return Content("<h1>Message from " + username + "</h1><div>" + message + "</div>", "text/html");
        }
    }
}
EOF
done

# =======================================
# 2. Create secure controller files (for contrast)
# =======================================
for i in {1..5}; do
  cat > $TEST_DIR/controllers/SecureController$i.cs << EOF
using System;
using System.Data.SqlClient;
using System.Web.Mvc;
using System.Text.Encodings.Web;

namespace TestProject.Controllers {
    [ValidateAntiForgeryToken]
    public class SecureController$i : Controller {
        private readonly string connectionString = "..."; // From config
        
        [HttpPost]
        public ActionResult Search(string searchTerm) {
            // Secure SQL query
            using (var conn = new SqlConnection(connectionString)) {
                conn.Open();
                var cmd = new SqlCommand("SELECT * FROM Products WHERE Name LIKE @SearchTerm", conn);
                cmd.Parameters.AddWithValue("@SearchTerm", "%" + searchTerm + "%");
                var reader = cmd.ExecuteReader();
                // Process results
            }
            
            // XSS prevention
            ViewBag.SearchResults = "Results for: " + HtmlEncoder.Default.Encode(searchTerm);
            return View();
        }
    }
}
EOF
done

# =======================================
# 3. Create insecure authentication files
# =======================================
cat > $TEST_DIR/services/UserService.cs << EOF
using System;
using System.Security.Cryptography;
using System.Text;

namespace TestProject.Services {
    public class UserService {
        // Insecure password hashing
        public string HashPassword(string password) {
            using (SHA1 sha1 = SHA1.Create()) {
                byte[] hashBytes = sha1.ComputeHash(Encoding.UTF8.GetBytes(password));
                return Convert.ToBase64String(hashBytes);
            }
        }
        
        public bool VerifyPassword(string password, string hashedPassword) {
            string computedHash = HashPassword(password);
            return computedHash == hashedPassword;
        }
    }
}
EOF

# =======================================
# 4. Create config files with secrets
# =======================================
cat > $TEST_DIR/config/appsettings.json << EOF
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password=PlainTextPassword123!"
  },
  "ApiSettings": {
    "ApiKey": "c8e5f279e4c94b1a96a0f6352431e9ee",
    "ApiSecret": "TotallySecretKeyThatShouldBeProtected"
  },
  "Jwt": {
    "Secret": "VeryLongSecretKeyThatShouldBeProtectedAndNotCheckedIntoSourceControl1234567890",
    "Issuer": "MyApp",
    "Audience": "MyWebsite"
  },
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft": "Warning"
    }
  }
}
EOF

# =======================================
# 5. Create files with very long lines (to test regex performance)
# =======================================
cat > $TEST_DIR/LongLineFile.cs << EOF
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TestProject {
    public class LongLineClass {
        public void MethodWithLongLine() {
            // This is a very long line to test regex performance
            string longString = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum." + "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
            
            // Another long line with a potential SQL injection vulnerability
            var query = "SELECT * FROM Users WHERE Name = '" + longString + "' AND Role = 'Admin' AND Status = 'Active' AND LoginAttempts < 5 AND LastLogin > '" + DateTime.Now.AddDays(-30).ToString("yyyy-MM-dd") + "' AND Email LIKE '%" + longString.Substring(0, 10) + "%' ORDER BY LastName, FirstName, MiddleName, DateOfBirth DESC";
        }
    }
}
EOF

# =======================================
# 6. Create many small files to test file handling performance
# =======================================
mkdir -p $TEST_DIR/many-files
for i in {1..100}; do
    cat > $TEST_DIR/many-files/SmallFile$i.cs << EOF
using System;

namespace TestProject.SmallFiles {
    public class SmallFile$i {
        public void Method$i() {
            Console.WriteLine("This is small file $i");
            // Minor vulnerability for testing: hardcoded password
            string password = "Password123!";
        }
    }
}
EOF
done

# =======================================
# 7. Create Razor views with XSS vulnerabilities
# =======================================
for i in {1..5}; do
  cat > $TEST_DIR/views/VulnerableView$i.cshtml << EOF
@model TestProject.Models.SearchModel

<h1>Search Results</h1>

<div>
    <!-- XSS vulnerability in Razor view -->
    <p>You searched for: @Model.SearchTerm</p>
    
    <!-- Another XSS vulnerability using Html.Raw -->
    <div class="results">@Html.Raw(Model.Results)</div>
    
    <script>
        // Potential DOM-based XSS
        var searchTerm = '@Model.SearchTerm';
        document.getElementById('searchBox').value = searchTerm;
    </script>
</div>
EOF
done

# Count files and report
FILE_COUNT=$(find $TEST_DIR -type f | wc -l)
echo "Test dataset generated with $FILE_COUNT files."
echo "Directory structure:"
find $TEST_DIR -type d | sort

echo "You can now run the performance test with:"
echo "./benchmark.sh baseline"
