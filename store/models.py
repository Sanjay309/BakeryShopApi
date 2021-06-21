from django.db import models


# Create your models here.

class Product(models.Model):
    # can choose name from provided choices also
    name=models.CharField(max_length=40)
    price = models.FloatField(null=True)
    description=models.CharField(max_length=40,null=True)
    date_created= models.DateField(auto_now_add=True,null=True)
    def __str__(self):
        return self.name


class Orders(models.Model):
    STATUS =(
        ('Pending','Pending'),
        ('Order Confirmed','Order Confirmed'),
        ('Out for Delivery','Out for Delivery'),
        ('Delivered','Delivered'),
    )
    coustomer=models.ForeignKey('accounts.User', on_delete=models.CASCADE,null=True)
    product=models.ForeignKey('Product',on_delete=models.CASCADE,null=True)
    order_date= models.DateField(auto_now_add=True,null=True)
    status=models.CharField(max_length=50,null=True,choices=STATUS)

