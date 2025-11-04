package com.wecp.medicalequipmentandtrackingsystem.controller;

import com.wecp.medicalequipmentandtrackingsystem.dto.EquipmentDTO;
import com.wecp.medicalequipmentandtrackingsystem.dto.HospitalDTO;
import com.wecp.medicalequipmentandtrackingsystem.entitiy.Equipment;
import com.wecp.medicalequipmentandtrackingsystem.entitiy.Hospital;
import com.wecp.medicalequipmentandtrackingsystem.entitiy.Maintenance;
import com.wecp.medicalequipmentandtrackingsystem.dto.MaintenanceScheduleDTO;
import com.wecp.medicalequipmentandtrackingsystem.dto.Mapper;
import com.wecp.medicalequipmentandtrackingsystem.entitiy.Order;
import com.wecp.medicalequipmentandtrackingsystem.service.EquipmentService;
import com.wecp.medicalequipmentandtrackingsystem.service.HospitalService;
import com.wecp.medicalequipmentandtrackingsystem.service.MaintenanceService;
import com.wecp.medicalequipmentandtrackingsystem.service.OrderService;
import com.wecp.medicalequipmentandtrackingsystem.utility.EquipmentMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.UUID;

import java.util.List;

import javax.validation.Valid;

@RestController
public class HospitalController {

    private HospitalService hospitalService;
    private MaintenanceService maintenanceService;
    private EquipmentService equipmentService;
    private OrderService orderService;
    private EquipmentMapper equipmentMapper;
    private static final Logger logger = LoggerFactory.getLogger(HospitalController.class);

    public HospitalController(HospitalService hospitalService, MaintenanceService maintenanceService,
            OrderService orderService , EquipmentService equipmentService, EquipmentMapper equipmentMapper) {
        this.hospitalService = hospitalService;
        this.maintenanceService = maintenanceService;
        this.orderService = orderService;
        this.equipmentService = equipmentService;
        this.equipmentMapper = equipmentMapper;
    }

    

    // create hospital and return the created hospital with status code 201 =
    // CREATED;
    @PostMapping("/api/hospital/create")
    public ResponseEntity<HospitalDTO> createHospital(@Valid @RequestBody HospitalDTO hospitalDTO) {
        logger.info("Creating hospital: {}", hospitalDTO.getName());
        try {
            HospitalDTO savedHospital = hospitalService.addHospital(hospitalDTO);
            logger.info("Hospital created successfully with ID: {}", savedHospital.getId());
            return new ResponseEntity<>(savedHospital, HttpStatus.CREATED);
        } catch (RuntimeException e) {
            logger.error("Hospital creation failed: {}", e.getMessage());
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        } catch (Exception e) {
            logger.error("Unexpected error during hospital creation", e);
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    // return all hospitals with response code = 200 ok
    @GetMapping("/api/hospitals")
    public ResponseEntity<List<HospitalDTO>> getAllHospitals() {
        logger.info("Fetching all hospitals");
        try {
            List<HospitalDTO> hospitals = hospitalService.getAllHospitals();
            logger.info("Fetched {} hospitals", hospitals.size());
            return new ResponseEntity<>(hospitals, HttpStatus.OK);
        } catch (Exception e) {
            logger.error("Error fetching hospitals", e);
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
    

    // add equipment to the hospital and return the added equipment with status code
    // 201 = CREATED;
    @PostMapping("/api/hospital/equipment")
    public ResponseEntity<Equipment> addEquipment(@RequestParam Long hospitalId,
            @Valid @RequestBody EquipmentDTO equipmentDTO) {
        String requestId = UUID.randomUUID().toString();
        logger.info("[{}] Request to add equipment: {}", requestId, equipmentDTO.getName());

        Equipment equipment = equipmentMapper.mapToEntity(equipmentDTO);
        Equipment savedEquipment = equipmentService.createEquipment(hospitalId, equipment);

        logger.info("[{}] Equipment '{}' added successfully for hospital ID: {}",
                requestId, equipmentDTO.getName(), hospitalId);

        return new ResponseEntity<>(savedEquipment, HttpStatus.CREATED);

    }

  

    // return all equipments of hospital with response code = 200 OK
    @GetMapping("/api/hospital/equipment/{hospitalId}")
    public ResponseEntity<List<Equipment>> getAllEquipmentsOfHospital(@PathVariable Long hospitalId) {
       
        String requestId = UUID.randomUUID().toString();
        logger.info("[{}] Fetching all equipments for hospital ID: {}", requestId, hospitalId);

        List<Equipment> equipments = equipmentService.getEquipmentsByHospitalId(hospitalId);
        logger.info("[{}] Retrieved {} equipments for hospital ID: {}", 
                    requestId, equipments.size(), hospitalId);

        return new ResponseEntity<>(equipments, HttpStatus.OK);
    }

    // schedule maintenance for the equipment and return the scheduled maintenance
    // with status code 201 = CREATED;
    @PostMapping("/api/hospital/maintenance/schedule")
    public ResponseEntity<Maintenance> scheduleMaintenance(@Valid @RequestBody MaintenanceScheduleDTO dto) {
        Equipment equipment = equipmentService.getEquipmentById(dto.getEquipmentId());
        Maintenance maintenance = Mapper.mapToEntity(dto, equipment);
        return new ResponseEntity<>(maintenanceService.createMaintenance(equipment.getId(), maintenance), HttpStatus.CREATED);
    }

    // place order for the equipment and return the placed order with status code
    // 201 = CREATED;
    @PostMapping("/api/hospital/order")
    public ResponseEntity<Order> placeOrder(@RequestParam Long equipmentId, @RequestBody Order order) {
        // place order for the equipment and return the placed order with status code
        // 201 = CREATED;
        return new ResponseEntity<>(orderService.createOrder(equipmentId, order), HttpStatus.CREATED);
    }

    @GetMapping("/api/hospitalname/equipment/{hospital}")
    public ResponseEntity<List<Equipment>> getAllEquipmentsOfHospitalByName(@PathVariable("hospital") String name) {
        // return all equipments of hospital with response code = 200 OK
        return new ResponseEntity<>(hospitalService.getAllEquipmentsByName(name), HttpStatus.OK);
    }
}
