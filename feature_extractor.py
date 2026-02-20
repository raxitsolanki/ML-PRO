import cv2
import numpy as np

def extract_fingerprint_features(image_path):
    """
    Updated fingerprint feature extractor
    Compatible with ML model (9-feature pipeline)

    Returns:
    {
        ridge_density: float,
        complexity_score: float,
        pattern_type: int
    }
    """

    # ===================== 1. LOAD IMAGE =====================
    img = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
    if img is None:
        raise ValueError("Fingerprint image could not be loaded")

    # Standardize size (VERY IMPORTANT)
    img = cv2.resize(img, (512, 512))

    # ===================== 2. QUALITY CHECK =====================
    if np.std(img) < 15:
        raise ValueError("Low quality / blurred fingerprint image")

    # ===================== 3. CONTRAST ENHANCEMENT =====================
    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
    enhanced = clahe.apply(img)

    # ===================== 4. NOISE REMOVAL =====================
    blur = cv2.GaussianBlur(enhanced, (5, 5), 0)

    # ===================== 5. BINARIZATION =====================
    _, binary = cv2.threshold(
        blur, 0, 255,
        cv2.THRESH_BINARY + cv2.THRESH_OTSU
    )
    binary = cv2.bitwise_not(binary)

    # ===================== 6. SKELETONIZATION =====================
    try:
        skeleton = cv2.ximgproc.thinning(binary)
    except:
        raise ImportError(
            "opencv-contrib-python is required "
            "(pip install opencv-contrib-python)"
        )

    # ===================== 7. RIDGE DENSITY (ROBUST ROI) =====================
    h, w = skeleton.shape
    roi_size = 140
    cy, cx = h // 2, w // 2

    roi = skeleton[
        cy - roi_size // 2 : cy + roi_size // 2,
        cx - roi_size // 2 : cx + roi_size // 2
    ]

    ridge_pixels = cv2.countNonZero(roi)
    ridge_density = ridge_pixels / (roi_size * roi_size)

    # Clamp for safety
    ridge_density = np.clip(ridge_density, 0.0, 1.0)

    # ===================== 8. COMPLEXITY SCORE (ORIENTATION ENERGY) =====================
    sobel_x = cv2.Sobel(enhanced, cv2.CV_64F, 1, 0, ksize=3)
    sobel_y = cv2.Sobel(enhanced, cv2.CV_64F, 0, 1, ksize=3)

    magnitude = np.sqrt(sobel_x**2 + sobel_y**2)
    complexity_score = np.mean(magnitude)

    # Normalize complexity score (important for ML stability)
    complexity_score = np.clip(complexity_score, 0, 100)

    # ===================== 9. PATTERN TYPE (HEURISTIC) =====================
    # NOTE: Approximation only (CNN required for medical-grade accuracy)
    if complexity_score < 30:
        pattern_type = 0   # Arch
    elif complexity_score < 65:
        pattern_type = 1   # Loop
    else:
        pattern_type = 2   # Whorl

    # ===================== 10. RETURN =====================
    return {
        'ridge_density': round(float(ridge_density), 4),
        'complexity_score': round(float(complexity_score), 2),
        'pattern_type': int(pattern_type)
    }
