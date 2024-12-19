from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import base64
from PIL import Image
import crypto
from steganographer import hideDataToImage, extractDataFromImage

app = Flask(__name__)
CORS(app)

@app.route('/embed', methods=['POST'])
def embed():
    try:
        file = request.files['file']
        image = request.files['image']
        password = request.form.get('password', '')
        mode = request.form.get('mode', 'lsb')

        input_image_path = 'temp_input_image.png'
        file_to_hide_path = 'temp_file_to_hide.txt'
        output_image_path = 'temp_output_image.png'

        # Save the uploaded image and file
        image.save(input_image_path)
        file.save(file_to_hide_path)

        # Hide data in the image
        hideDataToImage(input_image_path, file_to_hide_path, output_image_path, password, mode)

        # Read the output image and encode it to base64
        with open(output_image_path, "rb") as f:
            encoded_string = base64.b64encode(f.read()).decode('utf-8')

        # Clean up temporary files
        os.remove(input_image_path)
        os.remove(file_to_hide_path)
        os.remove(output_image_path)

        return jsonify({"image": encoded_string})
    except Exception as e:
        return jsonify({"message": str(e)}), 500

@app.route('/extract', methods=['POST'])
def extract():
    try:
        image = request.files['image']
        password = request.form.get('password', '')
        output_file_path = 'temp_output_file.txt'

        input_image_path = 'temp_input_image.png'

        # Save the uploaded image
        image.save(input_image_path)

        # Extract data from the image
        extractDataFromImage(input_image_path, output_file_path, password)

        # Read the extracted data and encode it to base64
        with open(output_file_path, "rb") as f:
            extracted_data = f.read()

        os.remove(input_image_path)
        os.remove(output_file_path)

        if extracted_data:
            encoded_string = base64.b64encode(extracted_data).decode('utf-8')
            plain_text_data = extracted_data.decode('utf-8', errors='ignore')
            return jsonify({
                "message": "File extracted successfully", 
                "data": encoded_string, 
                "plain_text_data": plain_text_data
            })
        else:
            return jsonify({"message": "No hidden file found"}), 400
    except Exception as e:
        return jsonify({"message": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
