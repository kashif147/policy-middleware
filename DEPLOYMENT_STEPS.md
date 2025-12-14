# Policy Middleware - Publishing and Deployment Steps

## Option 1: Publish to GitHub Packages (Recommended)

### Prerequisites

1. GitHub Personal Access Token with `write:packages` permission
2. npm CLI installed
3. Access to the GitHub repository: `kashif147/policy-middleware`

### Step 1: Build the Package Locally

```bash
cd policy-middleware
npm run build
```

This creates the `dist/` and `dist/esm/` directories with compiled files.

### Step 2: Configure npm for GitHub Packages

Create `.npmrc` in `policy-middleware/` directory:

```
@membership:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}
```

Then set environment variable:
```bash
export GITHUB_TOKEN=your_github_personal_access_token
```

### Step 3: Publish to GitHub Packages

```bash
cd policy-middleware
npm publish
```

This will:
- Run `prepublishOnly` script (builds the package)
- Publish to `@membership/policy-middleware` on GitHub Packages

### Step 4: Update user-service to Use Published Package

Update `user-service/package.json`:

```json
"dependencies": {
  "@membership/policy-middleware": "^1.0.0",
  // ... other dependencies
}
```

Remove the `file:../policy-middleware` reference.

### Step 5: Update user-service GitHub Actions Workflow

Update `.github/workflows/main_userserviceshell.yml`:

1. Remove the "Checkout policy-middleware" step
2. Remove the "Build policy-middleware" step
3. Remove the "Update package.json for deployment" step
4. Remove policy-middleware exclusions from zip command
5. Add GitHub Packages configuration:

```yaml
- name: Configure npm for GitHub packages
  run: |
    echo "@membership:registry=https://npm.pkg.github.com" >> .npmrc
    echo "@projectShell:registry=https://npm.pkg.github.com" >> .npmrc
    echo "//npm.pkg.github.com/:_authToken=${{ secrets.GITHUB_TOKEN }}" >> .npmrc
```

### Step 6: Test Locally

```bash
cd user-service

# Create .npmrc for local testing
echo "@membership:registry=https://npm.pkg.github.com" > .npmrc
echo "//npm.pkg.github.com/:_authToken=YOUR_TOKEN" >> .npmrc

rm -rf node_modules package-lock.json
npm install
npm start
```

### Step 7: Deploy to Azure

1. Commit and push changes to user-service repository
2. The GitHub Actions workflow will automatically deploy
3. No Azure App Settings needed (uses GitHub Actions secrets)

---

## Option 2: Fix Current Workflow (Quick Fix)

If you want to keep the current file-based approach, update the workflow to include `scripts/`:

### Update `.github/workflows/main_userserviceshell.yml`

Remove this line from the zip command (line 77):
```yaml
-x "policy-middleware/scripts/*"
```

The workflow should now include the scripts directory, allowing the `prepare` script to run during `npm install` on Azure.

---

## Option 3: Automated Publishing via GitHub Actions

Create `.github/workflows/publish.yml` in policy-middleware:

```yaml
name: Publish Package

on:
  push:
    tags:
      - 'v*'
  workflow_dispatch:

jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '22'
          registry-url: 'https://npm.pkg.github.com'
          scope: '@membership'
      
      - name: Install dependencies
        run: npm ci
      
      - name: Build package
        run: npm run build
      
      - name: Publish to GitHub Packages
        run: npm publish
        env:
          NODE_AUTH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

Then publish by creating a git tag:
```bash
git tag v1.0.0
git push origin v1.0.0
```

---

## Testing Checklist

- [ ] Policy middleware builds successfully (`npm run build`)
- [ ] Package publishes to GitHub Packages
- [ ] user-service installs package from GitHub Packages
- [ ] Local test: `npm start` works in user-service
- [ ] GitHub Actions workflow runs successfully
- [ ] Azure deployment completes without errors
- [ ] Service starts and responds to requests

## Troubleshooting

- **401 Unauthorized**: Check GitHub token has `write:packages` permission
- **404 Not Found**: Ensure package name matches GitHub org/username (`@membership/policy-middleware`)
- **Build fails in Azure**: Verify `scripts/` directory is included in deployment
- **Module not found**: Check `.npmrc` is configured correctly in workflow

