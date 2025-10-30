package com.wecp.medicalequipmentandtrackingsystem.entitiy;
 
 
import javax.persistence.*;
 
import com.fasterxml.jackson.annotation.JsonFormat;
 
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
 
import java.util.Date;
 
@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "orders") 
public class Order {
 
    @Id 
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    Long id;
 
    @JsonFormat(pattern = "yyyy-MM-dd")
    Date orderDate;
    //Pending , Shipped , Delivered
    String status = "Pending";  
    int quantity;
    @ManyToOne
    Equipment equipment;
 
}
