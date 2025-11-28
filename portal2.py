from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
import time
import os

password = os.getenv("AZURE_PASSWORD")

driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()))
driver.get("https://portal.azure.com")

time.sleep(3)

# Enter username
driver.find_element(By.ID, "i0116").send_keys("SECADM_EHanlon.Miller@nationalgridplc.onmicrosoft.com")
driver.find_element(By.ID, "idSIButton9").click()

time.sleep(2)

# Enter password
driver.find_element(By.ID, "i0118").send_keys(password)
driver.find_element(By.ID, "idSIButton9").click()

time.sleep(2)

# Stay signed in? -> Yes
try:
    driver.find_element(By.ID, "idSIButton9").click()
except:
    pass

# Optional: keep browser open
input("Press Enter to close...")
driver.quit()
