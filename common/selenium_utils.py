# common/selenium_utils.py
import os
import pyotp

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager


def create_driver():
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()))
    wait = WebDriverWait(driver, 20)
    return driver, wait


def login_to_azure_portal(driver, wait):
    username = os.getenv("AZURE_USERNAME")
    password = os.getenv("AZURE_PASSWORD")
    totp_secret = os.getenv("AZURE_TOTP_SECRET")

    if not username:
        raise ValueError("AZURE_USERNAME environment variable is not set.")
    if not password:
        raise ValueError("AZURE_PASSWORD environment variable is not set.")

    driver.get("https://portal.azure.com")

    # Username
    wait.until(EC.visibility_of_element_located((By.ID, "i0116"))).send_keys(username)
    driver.find_element(By.ID, "idSIButton9").click()

    # Password
    wait.until(EC.visibility_of_element_located((By.ID, "i0118"))).send_keys(password)
    driver.find_element(By.ID, "idSIButton9").click()

    # TOTP MFA (optional)
    if totp_secret:
        try:
            totp = pyotp.TOTP(totp_secret, interval=60).now()
            code_box = WebDriverWait(driver, 20).until(
                EC.visibility_of_element_located((By.ID, "idTxtBx_SAOTCC_OTC"))
            )
            code_box.send_keys(totp)
            driver.find_element(By.ID, "idSubmit_SAOTCC_Continue").click()
        except Exception as e:
            print(f"[MFA] No TOTP prompt or failed to enter code: {e}")

    # Stay signed in? Yes
    try:
        stay_btn = WebDriverWait(driver, 20).until(
            EC.element_to_be_clickable((By.ID, "idSIButton9"))
        )
        stay_btn.click()
    except Exception:
        pass

    print("[Selenium] Logged into Azure Portal.")


def open_saml_sso_blade(driver, sp_id, app_id):
    url = (
        "https://portal.azure.com/"
        "#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/SignOn"
        f"/objectId/{sp_id}"
        f"/appId/{app_id}"
        "/preferredSingleSignOnMode/saml"
        "/servicePrincipalType/Application/fromNav/"
    )
    print(f"[Selenium] Opening SAML SSO blade: {url}")
    driver.get(url)