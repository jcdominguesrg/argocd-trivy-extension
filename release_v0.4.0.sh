#!/usr/bin/env bash
set -euo pipefail

confirm() {
  read -r -p "$1 [y/N]: " ans
  case "$ans" in
    [yY][eE][sS]|[yY]) return 0 ;;
    *) return 1 ;;
  esac
}

echo "This script will help you build and publish v0.4.0 of the extension."
echo "Run it from the repository root: /Users/julio.cardoso/Documents/argocd-trivy-extension"

echo "\nCurrent git status and last commits:"
git branch -vv
git log --oneline -n 5
git status --short || true

if confirm "Step 1: Update package.json version to 0.4.0 (npm version --no-git-tag-version)?"; then
  npm version 0.4.0 --no-git-tag-version
  echo "package.json updated. Diff:";
  git --no-pager diff -- package.json | sed -n '1,200p' || true
else
  echo "Skipping version bump"
fi

if confirm "Step 2: Run build (npm run build)?"; then
  npm run build
  echo "Build complete. artifact:";
  ls -lh dist/resources/extension-trivy.tar || true
  echo "Contents (top 50):";
  tar -tf dist/resources/extension-trivy.tar | sed -n '1,50p' || true
else
  echo "Skipping build"
fi

if confirm "Step 3: Stage and commit changes (git add/commit)?"; then
  git add -A
  if git diff --cached --quiet; then
    echo "No staged changes to commit."
  else
    git commit -m "chore(release): v0.4.0 - sync src and fixes"
    echo "Committed: $(git rev-parse --short HEAD)";
  fi
else
  echo "Skipping commit"
fi

if confirm "Step 4: Create or update tag v0.4.0 locally? (this will overwrite local tag if exists)"; then
  git tag -f v0.4.0
  echo "Local tag v0.4.0 set to $(git rev-parse --short v0.4.0)"
else
  echo "Skipping local tag creation"
fi

if confirm "Step 5: Push branch 'main' to origin?"; then
  git push origin main
else
  echo "Skipping push of main"
fi

if confirm "Step 6: Push tag 'v0.4.0' to origin? (if tag exists remotely you may need to force or delete remote tag first)"; then
  if git ls-remote --tags origin | grep -q "refs/tags/v0.4.0"; then
    echo "Remote tag v0.4.0 exists. You will be asked to confirm whether to force-push it."
    if confirm "Force push the tag (this will overwrite the remote tag)?"; then
      git push -f origin v0.4.0
    else
      echo "Skipping force-push of tag. To replace remote tag manually: git push origin :refs/tags/v0.4.0 && git push origin v0.4.0"
    fi
  else
    git push origin v0.4.0
  fi
else
  echo "Skipping push of tag"
fi

if command -v gh >/dev/null 2>&1; then
  if confirm "Step 7: Create or update GitHub Release v0.4.0 using gh and upload asset dist/resources/extension-trivy.tar?"; then
    if gh release view v0.4.0 >/dev/null 2>&1; then
      echo "Release exists. Uploading (clobber) asset..."
      gh release upload v0.4.0 dist/resources/extension-trivy.tar --clobber
    else
      echo "Creating new release and uploading asset..."
      gh release create v0.4.0 dist/resources/extension-trivy.tar --title "v0.4.0" --notes "v0.4.0 — sincroniza src e corrige fallback para nomes encurtados de VulnerabilityReport; fallback para métricas indisponíveis."
    fi
  else
    echo "Skipping GitHub Release step"
  fi
else
  echo "gh CLI not found. To create a release use GitHub UI: https://github.com/jcdominguesrg/argocd-trivy-extension/releases"
fi

echo "\nAll done. Verify the release on GitHub and test the extension in Argo." 
