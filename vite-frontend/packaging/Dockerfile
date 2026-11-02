# Offline runtime: context must contain dist/ and nginx.conf from this branch.
FROM nginx:stable-alpine
COPY nginx.conf /etc/nginx/nginx.conf
COPY dist/ /usr/share/nginx/html/
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
