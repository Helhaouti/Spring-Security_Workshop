package nl.hva.springsecuritydemo.exceptions;

public class ForbiddenResourceAccessed extends RuntimeException {

    public ForbiddenResourceAccessed(String message) {
        super(message);
    }

}