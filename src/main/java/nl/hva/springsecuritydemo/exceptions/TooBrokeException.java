package nl.hva.springsecuritydemo.exceptions;

public class TooBrokeException extends RuntimeException {

    public TooBrokeException(String message) {
        super(message);
    }

}
