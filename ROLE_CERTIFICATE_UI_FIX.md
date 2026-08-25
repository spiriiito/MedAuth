# Role and Certificate UI Isolation Fix

This focused regression fix keeps medical document-signing certificates separate from mTLS client-authentication certificates. It does not change certificate ownership, Hyperledger Fabric, or mTLS behavior.

## Manual acceptance test

1. Start Fabric.
2. Start MedAuth.
3. Open the browser dashboard.
4. Login as `surgeon1`.
5. Note the displayed medical document-signing certificate serial.
6. Logout without refreshing.
7. Login as `admin`.
8. Verify:
   - the `surgeon1` serial is not visible;
   - the Upload page is not visible;
   - the Doctor Certificate Identity card is not presented as the admin identity;
   - the Admin dashboard opens;
   - the profile displays `Authenticated Admin`.
9. In browser DevTools, call the own-certificate endpoint with the admin token:

   ```js
   fetch('/api/uploads/certificate/own', {
     headers: { Authorization: `Bearer ${state.token}` }
   }).then(async response => ({ status: response.status, body: await response.json() }))
   ```

10. Verify HTTP 403 with `Doctor role required`.
11. Logout.
12. Login as another doctor without a certificate.
13. Verify the UI says no active certificate, with no `surgeon1` data.
14. Login again as `surgeon1`.
15. Verify `surgeon1`'s correct certificate appears.
16. Perform one valid upload.
17. Confirm the upload still commits to Hyperledger Fabric.

## Automated regression

With MedAuth running on its configured HTTPS port, run:

```bash
npm run test:role-ui
```

The test uses a local headless Chrome instance against the real SPA. It covers doctor-to-admin and doctor-to-auditor transitions without refresh, direct admin login, backend 403 enforcement, a doctor with no certificate, doctor-to-doctor switching, and a deliberately delayed stale certificate response.

The test registers one uniquely named doctor without issuing a certificate. It does not delete or reassign any existing users, certificates, uploads, or database records.
