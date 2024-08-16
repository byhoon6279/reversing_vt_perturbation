git add .

# 커밋 생성
git commit -m "$COMMIT_MESSAGE"

# 원격 저장소로 푸시
git push origin

echo "Changes have been pushed to GitHub with message: $COMMIT_MESSAGE"