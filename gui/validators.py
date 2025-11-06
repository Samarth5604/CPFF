import re

class Validator:
    @staticmethod
    def validate_inline(field, le):
        text = le.text().strip()
        if not text:
            le.setStyleSheet("")
            return
        if field in ("src_ip", "dst_ip"):
            valid = re.match(r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$", text)
        elif field == "dst_port":
            valid = re.match(r"^\d{1,5}$", text)
        elif field == "geoip_country":
            valid = re.match(r"^[A-Za-z]{2}$", text)
        else:
            valid = True
        le.setStyleSheet("border: 2px solid green;" if valid else "border: 2px solid red;")
