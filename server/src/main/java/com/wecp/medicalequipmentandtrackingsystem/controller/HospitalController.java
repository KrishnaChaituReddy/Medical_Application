package com.wecp.medicalequipmentandtrackingsystem.controller;


import com.wecp.medicalequipmentandtrackingsystem.entitiy.Equipment;
import com.wecp.medicalequipmentandtrackingsystem.entitiy.Hospital;
import com.wecp.medicalequipmentandtrackingsystem.entitiy.Maintenance;
import com.wecp.medicalequipmentandtrackingsystem.entitiy.Order;
import com.wecp.medicalequipmentandtrackingsystem.service.EquipmentService;
import com.wecp.medicalequipmentandtrackingsystem.service.HospitalService;
import com.wecp.medicalequipmentandtrackingsystem.service.MaintenanceService;
import com.wecp.medicalequipmentandtrackingsystem.service.OrderService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
public class HospitalController {

    @Autowired
    HospitalService hospitalService;
    @Autowired
    EquipmentService equipmentService;
    @Autowired
    MaintenanceService maintenanceService;
    @Autowired
    OrderService orderService;

    // create hospital and return the created hospital with status code 201 = CREATED;
    @PostMapping("/api/hospital/create")
    public ResponseEntity<Hospital> createHospital(@RequestBody Hospital hospital) {
        try{
            return new ResponseEntity<>(hospitalService.addHospital(hospital), HttpStatus.CREATED);
            //return new ResponseEntity<Hospital>(hospital, null)
        }
        catch(RuntimeException e){
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
        catch(Exception e){
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
        
    }

    
    // return all hospitals with response code = 200 ok
    @GetMapping("/api/hospitals")
    public ResponseEntity<List<Hospital>> getAllHospitals() {
        try{
            return new ResponseEntity<>(hospitalService.getAllHospitals(), HttpStatus.OK);
        }
        catch(Exception e){
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
        
    }

    // add equipment to the hospital and return the added equipment with status code 201 = CREATED;
    @PostMapping("/api/hospital/equipment")
    public ResponseEntity<Equipment> addEquipment(@RequestParam Long hospitalId, @RequestBody Equipment equipment) {
        return new ResponseEntity<>(hospitalService.addEquipment(hospitalId , equipment), HttpStatus.CREATED);
        
    }

    // return all equipments of hospital with response code = 200 OK
    @GetMapping("/api/hospital/equipment/{hospitalId}")
    public ResponseEntity<List<Equipment>> getAllEquipmentsOfHospital(@PathVariable Long hospitalId) {
        // return all equipments of hospital with response code = 200 OK
        return new ResponseEntity<>(hospitalService.getAllEquipmentsById(hospitalId), HttpStatus.OK);
    }

    // schedule maintenance for the equipment and return the scheduled maintenance with status code 201 = CREATED;
    @PostMapping("/api/hospital/maintenance/schedule")
    public ResponseEntity<Maintenance> scheduleMaintenance
            (@RequestParam Long equipmentId, @RequestBody Maintenance maintenance) {
        // schedule maintenance for the equipment and return the scheduled maintenance with status code 201 = CREATED;
        return new ResponseEntity<>(maintenanceService.createMaintenance(equipmentId, maintenance), HttpStatus.CREATED);
    }

     // place order for the equipment and return the placed order with status code 201 = CREATED;
    @PostMapping("/api/hospital/order")
    public ResponseEntity<Order> placeOrder(@RequestParam Long equipmentId, @RequestBody Order order) {
        // place order for the equipment and return the placed order with status code 201 = CREATED;
        return new ResponseEntity<>(orderService.createOrder(equipmentId, order), HttpStatus.CREATED);
    }
}

