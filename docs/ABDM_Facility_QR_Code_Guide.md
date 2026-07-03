# ABDM Sandbox v3 Facility QR Code Generation Guide

## Problem Statement
When generating a QR code for ABDM sandbox facility using URL `https://iplitdev.bahmni.in/share-profile?hip-id=IN2710001820&counter-id=12345`, the PHR app throws "invalid QR code" error.

## Root Cause
The QR code URL must point to **ABDM's sandbox domain** (`phrsbx.abdm.gov.in`), not your facility's domain. PHR apps are configured to recognize and validate QR codes only from ABDM's official domains.

## Correct QR Code URL Format

### For ABDM Sandbox v3:
```
https://phrsbx.abdm.gov.in/share-profile?hip-id=IN2710001820&counter-id=12345
```

### URL Parameters:
- **hip-id** (Required): Your registered HIP ID (e.g., `IN2710001820`)
  - Must be a valid Health Facility Registry ID or HIP ID linked with your client ID
  - For sandbox testing, use the HIP ID associated with your client ID registered in ABDM sandbox

- **counter-id** (Optional): Facility counter identifier
  - Can be any facility-decided alphanumeric string
  - Identifies the physical location/counter where the QR code is displayed
  - This value is passed back to your facility as part of the share-profile API callback in the `context` field

## How It Works

1. **Patient scans QR code** from PHR app
2. **PHR app opens** the URL pointing to `phrsbx.abdm.gov.in`
3. **ABDM Gateway verifies** the registered healthcare provider (HIP)
4. **Gateway calls your callback URL**: `/api/v3/hip/patient/share`
   - Your callback URL is configured in ABDM sandbox registration
   - The callback URL should be: `https://iplitdev.bahmni.in/api/v3/hip/patient/share`
5. **Your HIP service receives** the `ShareProfileRequest` with patient profile data
6. **Your service processes** the request and responds with acknowledgment

## Implementation Details

### Backend Endpoint (Already Implemented)
Your HIP service already has the endpoint configured:
- **Path**: `/api/v3/hip/patient/share` (defined in `Constants.PATH_PROFILE_SHARE`)
- **Controller**: `PatientController.StoreDetails()`
- **Method**: POST
- **Request Body**: `ShareProfileRequest` containing:
  - `Intent`: Share profile intent
  - `Metadata`: Contains `HipId`, `Context` (counter-id), `HprId`, `Latitude`, `Longitude`
  - `Profile`: Patient profile with ABHA address and demographics

### Callback URL Configuration
Ensure your callback URL is registered in ABDM sandbox:
- **Callback URL**: `https://iplitdev.bahmni.in/api/v3/hip/patient/share`
- This URL must be publicly accessible and HTTPS enabled
- Must be registered in your ABDM sandbox client configuration

## Steps to Generate QR Code

1. **Use the correct URL format**:
   ```
   https://phrsbx.abdm.gov.in/share-profile?hip-id=IN2710001820&counter-id=12345
   ```

2. **Generate QR code** using any QR code generator:
   - Website: https://www.the-qrcode-generator.com
   - Or any other QR code generator tool

3. **Replace placeholders**:
   - Replace `IN2710001820` with your actual registered HIP ID
   - Replace `12345` with your facility counter ID (optional, can be any value)

4. **Test the QR code**:
   - Scan with ABDM PHR app (sandbox version)
   - Verify that the share-profile callback is received at your endpoint

## Example QR Code URLs

### For Sandbox Testing:
```
https://phrsbx.abdm.gov.in/share-profile?hip-id=IN2710001820&counter-id=COUNTER-01
```

### With Multiple Counters:
```
https://phrsbx.abdm.gov.in/share-profile?hip-id=IN2710001820&counter-id=REGISTRATION-DESK-1
https://phrsbx.abdm.gov.in/share-profile?hip-id=IN2710001820&counter-id=REGISTRATION-DESK-2
https://phrsbx.abdm.gov.in/share-profile?hip-id=IN2710001820&counter-id=OPD-ROOM-5
```

## Important Notes

1. **Domain Requirement**: The QR code URL **MUST** use `phrsbx.abdm.gov.in` domain for sandbox
2. **Production**: For production, use `phr.abdm.gov.in` (without 'sbx')
3. **HTTPS**: Your callback URL must be HTTPS enabled
4. **HIP ID**: Must match the HIP ID registered in ABDM sandbox
5. **Counter ID**: Will be returned in the `ShareProfileRequest.Metadata.Context` field

## Verification Checklist

- [ ] QR code URL uses `phrsbx.abdm.gov.in` domain
- [ ] HIP ID matches your ABDM sandbox registration
- [ ] Callback URL (`/api/v3/hip/patient/share`) is publicly accessible
- [ ] Callback URL is HTTPS enabled
- [ ] Callback URL is registered in ABDM sandbox configuration
- [ ] Backend endpoint is properly implemented and responding

## Troubleshooting

### Issue: "Invalid QR code" error in PHR app
**Solution**: Ensure the QR code URL uses `phrsbx.abdm.gov.in` domain, not your facility domain

### Issue: Callback not received
**Solution**: 
- Verify callback URL is registered in ABDM sandbox
- Check that your endpoint is publicly accessible
- Verify HTTPS is enabled

### Issue: Invalid HIP ID error
**Solution**: 
- Verify HIP ID matches your ABDM sandbox registration
- Check that HIP ID is linked with your client ID in sandbox

## References

- ABDM Sandbox Documentation: https://kiranma72.github.io/abdm-docs/
- ABDM Sandbox API Specifications
- Health Facility QR Scan Documentation
