# Railway Domain Setup Guide

## Quick Steps

1. **In Railway Dashboard:**
   - Go to your service → Settings → Domains
   - Click "Add Domain" or "Generate Domain"
   - Enter your domain (e.g., `vaultvision.com`)

2. **Get DNS Records:**
   - Railway will show you the CNAME record to add
   - Usually looks like: `[project].up.railway.app`

3. **Add DNS at Your Registrar:**
   - Log into your domain registrar (GoDaddy, Namecheap, Cloudflare, etc.)
   - Go to DNS Management
   - Add CNAME record:
     - **Type:** CNAME
     - **Name:** @ (for root) or www (for subdomain)
     - **Value:** [your-railway-domain].up.railway.app
     - **TTL:** 3600 (or default)

4. **Wait for Propagation:**
   - DNS changes take 5 minutes to 48 hours
   - Railway will auto-generate SSL certificate (Let's Encrypt)

5. **Verify:**
   - Check DNS: `dig vaultvision.com CNAME`
   - Railway dashboard will show "Active" when ready

## Common Registrars

### Cloudflare
- DNS → Records → Add record
- Type: CNAME
- Name: @ or www
- Target: [railway-domain].up.railway.app
- Proxy: OFF (gray cloud) for direct connection

### GoDaddy
- DNS Management → Add
- Type: CNAME
- Host: @ or www
- Points to: [railway-domain].up.railway.app

### Namecheap
- Domain List → Manage → Advanced DNS
- Add New Record
- Type: CNAME Record
- Host: @ or www
- Value: [railway-domain].up.railway.app

## Notes

- Railway automatically handles SSL certificates
- Use CNAME for subdomains, A record for root (if supported)
- Some registrars require ALIAS/ANAME instead of CNAME for root domain
- Check Railway logs if domain doesn't work after 24 hours
