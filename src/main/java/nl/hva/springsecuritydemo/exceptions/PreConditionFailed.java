package nl.hva.springsecuritydemo.exceptions;

public class PreConditionFailed extends RuntimeException {

    public PreConditionFailed(String message) {
        super(message);
    }

}