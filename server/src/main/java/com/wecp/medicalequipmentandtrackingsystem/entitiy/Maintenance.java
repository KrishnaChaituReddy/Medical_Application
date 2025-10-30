package com.wecp.medicalequipmentandtrackingsystem.entitiy;

import javax.persistence.*;
import com.fasterxml.jackson.annotation.JsonFormat;
import java.util.Date;
import lombok.*;


@Entity
@Table(name = "maintenances")
@Getter
@Setter
@NoArgsConstructor 
@AllArgsConstructor
public class Maintenance {

    @Id // Define's the primary key in the table
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    long id;

    @JsonFormat(pattern = "yyyy-MM-dd")
    Date scheduledDate;

    @JsonFormat(pattern = "yyyy-MM-dd")
    Date completedDate;

    String description;
    String status;

    @ManyToOne // ManyToOne relationship
    Equipment equipment;

    // parameterized constructor 1
    public Maintenance(Date scheduledDate, Date completedDate, String description, String status) {
        this.scheduledDate = scheduledDate;
        this.completedDate = completedDate;
        this.description = description;
        this.status = status;
    }

    // parameterized constructor 2
    public Maintenance(Date scheduledDate, Date completedDate, String description, String status, Equipment equipment) {

        this.scheduledDate = scheduledDate;
        this.completedDate = completedDate;
        this.description = description;
        this.status = status;
        this.equipment = equipment;

    }
}