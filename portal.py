from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
import time

# Create the Chrome driver
driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()))

# Open Azure Portal
driver.get("https://portal.azure.com")

time.sleep(3)  # wait for MS login page to load

# Enter username
username = "SECADM_EHanlon.Miller@nationalgridplc.onmicrosoft.com"
driver.find_element(By.ID, "i0116").send_keys(username)

# Click Next
driver.find_element(By.ID, "idSIButton9").click()

# Keep browser open (optional)
input("Press Enter to close...")
driver.quit()
