package com.wecp.medicalequipmentandtrackingsystem.exceptions;

public class HospitalAlreadyExists extends RuntimeException{

    public HospitalAlreadyExists(String message){
        super(message);
    }

}
