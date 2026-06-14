import numpy as np
from PIL import Image
import io
import base64

def visualize_pe(filepath: str) -> dict:
    """Convert PE file bytes into a grayscale PNG image as a base64 encoded string."""
    try:
        # 1. Read file bytes
        with open(filepath, "rb") as f:
            data = f.read()

        # 2. Convert to numpy array
        byte_array = np.frombuffer(data, dtype=np.uint8)

        # 3. Reshape to width 512
        width = 512
        height = len(byte_array) // width
        if height == 0:
            return {"error": "File too small to visualize (less than 512 bytes)"}
        
        # Trim to exact multiple of width
        trimmed = byte_array[:height * width]
        image_data = trimmed.reshape((height, width))

        # 4. Create grayscale image and convert to base64
        img = Image.fromarray(image_data, mode="L")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        image_base64 = base64.b64encode(buf.getvalue()).decode("utf-8")

        return {
            "image_base64": image_base64,
            "file_size_bytes": len(data),
            "image_width": width,
            "image_height": height
        }
    except Exception as e:
        return {"error": f"Visualization failed: {str(e)}"}
