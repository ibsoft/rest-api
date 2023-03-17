def verify_otp(key, otp):
    """Verify a one-time password (OTP) against a secret key"""
    
    # Generate the current TOTP and the previous/future ones
    interval = 30
    curr_time = int(time.time())
    curr_interval = curr_time // interval
    prev_interval = curr_interval - 1
    next_interval = curr_interval + 1
    
    curr_otp = generate_totp(key, curr_interval)
    prev_otp = generate_totp(key, prev_interval)
    next_otp = generate_totp(key, next_interval)
    
    # Check if the OTP matches any of the TOTPs
    if otp == curr_otp or otp == prev_otp or otp == next_otp:
        return True
    else:
        return False


