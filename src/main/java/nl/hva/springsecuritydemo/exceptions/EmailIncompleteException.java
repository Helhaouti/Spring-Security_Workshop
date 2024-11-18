package nl.hva.springsecuritydemo.exceptions;

public class EmailIncompleteException extends RuntimeException {

    public EmailIncompleteException(String message) {
        super(message);
    }

}
