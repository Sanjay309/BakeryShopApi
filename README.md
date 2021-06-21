# Build and run container
docker-compose build
docker-compose up


# Create admin or superuser
docker exec bakeryshopapi_web_1 python manage.py create_admin
docker exec bakeryshopapi_web_1 python manage.py add_moderators

# Postman Collection for API's
https://www.getpostman.com/collections/b5107943214d872497ea