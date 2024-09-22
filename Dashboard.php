<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Dashboard</title>
  <link rel="stylesheet" type="text/css" href="CSS/dashboard.css">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css" crossorigin="anonymous" referrerpolicy="no-referrer" />
</head>
<body>
  <div class="sidebar">
    <header>
      <img src="profile.png" alt="profile"/><br>
      ADMINISTRATOR
    </header>
              <ul>
              <li><a href="Dashboard.php"><i class='fa-solid fa-house' style='font-size:30px'></i>Home</a></li>
              <li><a href="Product.php"><i class='fas fa-archive' style='font-size:30px'></i>Product</a></li>
              <li><a href="Vendor.php"><i class='fa-solid fa-user' style='font-size:30px'></i>Vendor</a></li>
              <li><a href="StockEntry.php"><i class='fa-solid fa-arrow-trend-up' style='font-size:30px'></i>Stock Entry</a></li>
              <li><a href="Brand.php"><i class='fa-solid fa-tag' style='font-size:30px'></i>Brand</a></li>
              <li><a href="Category.php"><i class='fa-solid fa-layer-group' style='font-size:30px'></i>Category</a></li>
              <li><a href="Records.php"><i class='fa-solid fa-database' style='font-size:30px'></i>Records</a></li>
              <li><a href="SalesHistory.php"><i class='fa-solid fa-clock-rotate-left' style='font-size:30px'></i>Sales History</a></li>
              <li><a href="UserSettings.php"><i class='fa-solid fa-gear' style='font-size:30px'></i>User Settings</a></li>
              <li><a href="Login.php"><i class='fa-solid fa-arrow-right-from-bracket' style='font-size:30px'></i>Logout</a></li>
              </ul>
  </div>
  
  <div class="container">
    <div class="orange" id="box1">10,500,00 <br> DAILY SALES</div>
    <div class="yellow" id="box2">5,782 <br> STOCK ON HAND</div>
    <div class="green" id="box3">3<br> CRITICAL ITEMS</div>
  </div>

  <div class="pie-chart">
    <div class="slice" style="--percentage: 30;"></div>
    <div class="slice" style="--percentage: 20;"></div>
    <div class="text-at-40">40%</div>
    <div class="text-at-60">60%</div>
    <div class="slice" style="--percentage: 50;"></div>
    <div class="inner-circle"></div>
  </div>

  <div class="small-container">
    <div class="first box-container">2023</div>
    <div class="second box-container">2024</div>
  </div>
</body>
</html>
