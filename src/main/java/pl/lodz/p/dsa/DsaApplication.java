package pl.lodz.p.dsa;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

public class DsaApplication extends Application {
    private static final int P_BITS = 1024;
    private static final int Q_BITS = 160;

    private final DsaAlgorithm dsa = new DsaAlgorithm();

    private DsaParameters parameters;
    private DsaKeyPair keyPair;
    private byte[] loadedFileData;
    private String loadedFileName;

    private TextArea inputArea;
    private TextArea keysArea;
    private TextField rField;
    private TextField sField;
    private Label dataSourceLabel;
    private Label statusLabel;
    private Button signButton;
    private Button verifyButton;
    private Button generateButton;

    public static void main(String[] args) {
        launch(args);
    }

    @Override
    public void start(Stage stage) {
        inputArea = new TextArea();
        inputArea.setPromptText("Wpisz dane do podpisania albo wczytaj plik...");
        inputArea.setWrapText(true);
        inputArea.setPrefRowCount(8);

        dataSourceLabel = new Label("Zrodlo danych: tekst wpisany recznie");
        dataSourceLabel.setWrapText(true);

        keysArea = new TextArea();
        keysArea.setEditable(false);
        keysArea.setWrapText(true);
        keysArea.setPrefRowCount(8);

        rField = new TextField();
        rField.setPromptText("wartosc hex pierwszej czesci podpisu");
        sField = new TextField();
        sField.setPromptText("wartosc hex drugiej czesci podpisu");

        Button loadButton = new Button("Wczytaj plik");
        loadButton.setOnAction(event -> loadFile(stage));

        Button textButton = new Button("Wpisz tekst");
        textButton.setOnAction(event -> switchToTextInput());

        Button clearButton = new Button("Wyczysc dane");
        clearButton.setOnAction(event -> clearData());

        generateButton = new Button("Generuj klucze");
        generateButton.setOnAction(event -> generateKeys());

        signButton = new Button("Podpisz");
        signButton.setDisable(true);
        signButton.setOnAction(event -> signData());

        verifyButton = new Button("Weryfikuj");
        verifyButton.setDisable(true);
        verifyButton.setOnAction(event -> verifySignature());

        statusLabel = new Label("Najpierw wygeneruj klucze albo wczytaj dane.");
        statusLabel.setWrapText(true);

        GridPane signaturePane = new GridPane();
        signaturePane.setHgap(8);
        signaturePane.setVgap(8);
        signaturePane.add(new Label("Podpis - czesc 1 (r):"), 0, 0);
        signaturePane.add(rField, 1, 0);
        signaturePane.add(new Label("Podpis - czesc 2 (s):"), 0, 1);
        signaturePane.add(sField, 1, 1);
        GridPane.setHgrow(rField, Priority.ALWAYS);
        GridPane.setHgrow(sField, Priority.ALWAYS);

        HBox fileButtons = new HBox(8, loadButton, textButton, clearButton);
        HBox actionButtons = new HBox(8, generateButton, signButton, verifyButton);

        VBox root = new VBox(
                10,
                new Label("Dane"),
                dataSourceLabel,
                inputArea,
                fileButtons,
                new Label("Klucze"),
                keysArea,
                actionButtons,
                new Label("Podpis"),
                signaturePane,
                statusLabel
        );
        root.setPadding(new Insets(12));
        VBox.setVgrow(inputArea, Priority.ALWAYS);
        VBox.setVgrow(keysArea, Priority.ALWAYS);

        Scene scene = new Scene(root, 820, 720);
        stage.setTitle("DSA - podpis cyfrowy");
        stage.setScene(scene);
        stage.show();
    }

    private void loadFile(Stage stage) {
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Wybierz plik z danymi");
        File file = chooser.showOpenDialog(stage);
        if (file == null) {
            return;
        }

        try {
            loadedFileData = Files.readAllBytes(file.toPath());
            loadedFileName = file.getName();
            inputArea.setEditable(false);
            inputArea.setText("Wczytano plik: " + loadedFileName + System.lineSeparator()
                    + "Rozmiar: " + loadedFileData.length + " bajtow" + System.lineSeparator());
            dataSourceLabel.setText("Zrodlo danych: plik " + loadedFileName);
            statusLabel.setText("Wczytano plik: " + loadedFileName + " (" + loadedFileData.length + " bajtow).");
        } catch (IOException exception) {
            statusLabel.setText("Nie udalo sie wczytac pliku: " + exception.getMessage());
        }
    }

    private void switchToTextInput() {
        loadedFileData = null;
        loadedFileName = null;
        inputArea.setEditable(true);
        inputArea.clear();
        dataSourceLabel.setText("Zrodlo danych: tekst wpisany recznie");
        statusLabel.setText("Mozesz wpisac tekst do podpisania.");
    }

    private void clearData() {
        loadedFileData = null;
        loadedFileName = null;
        inputArea.setEditable(true);
        inputArea.clear();
        rField.clear();
        sField.clear();
        dataSourceLabel.setText("Zrodlo danych: tekst wpisany recznie");
        statusLabel.setText("Dane zostaly wyczyszczone.");
    }

    private void generateKeys() {
        setBusy(true, "Generowanie parametrow i kluczy DSA...");

        Thread worker = new Thread(() -> {
            try {
                DsaParameters generatedParameters = dsa.generateParameters(P_BITS, Q_BITS);
                DsaKeyPair generatedKeyPair = dsa.generateKeyPair(generatedParameters);
                Platform.runLater(() -> {
                    parameters = generatedParameters;
                    keyPair = generatedKeyPair;
                    keysArea.setText(formatKeys());
                    signButton.setDisable(false);
                    verifyButton.setDisable(false);
                    setBusy(false, "Wygenerowano klucze DSA.");
                });
            } catch (RuntimeException exception) {
                Platform.runLater(() -> setBusy(false, "Blad generowania kluczy: " + exception.getMessage()));
            }
        });
        worker.setDaemon(true);
        worker.start();
    }

    private void signData() {
        if (!hasKeys()) {
            statusLabel.setText("Brak kluczy.");
            return;
        }

        byte[] data = currentData();
        DsaSignature signature = dsa.sign(data, parameters, keyPair.privateKey());
        rField.setText(toHex(signature.r()));
        sField.setText(toHex(signature.s()));
        statusLabel.setText("Dane zostaly podpisane: " + currentDataDescription() + ".");
    }

    private void verifySignature() {
        if (!hasKeys()) {
            statusLabel.setText("Brak klucza publicznego.");
            return;
        }

        try {
            DsaSignature signature = new DsaSignature(fromHex(rField.getText()), fromHex(sField.getText()));
            byte[] data = currentData();
            boolean valid = dsa.verify(data, keyPair.publicKey(), signature);
            statusLabel.setText(valid ? "Podpis jest prawidlowy." : "Podpis jest nieprawidlowy.");
        } catch (NumberFormatException exception) {
            statusLabel.setText("Obie czesci podpisu musza zawierac liczby szesnastkowe.");
        }
    }

    private boolean hasKeys() {
        return parameters != null && keyPair != null;
    }

    private byte[] currentData() {
        if (loadedFileData != null) {
            return loadedFileData;
        }
        return inputArea.getText().getBytes(StandardCharsets.UTF_8);
    }

    private String currentDataDescription() {
        if (loadedFileData != null) {
            return "plik " + loadedFileName + ", " + loadedFileData.length + " bajtow";
        }
        return "tekst, " + currentData().length + " bajtow UTF-8";
    }

    private void setBusy(boolean busy, String message) {
        generateButton.setDisable(busy);
        signButton.setDisable(busy || !hasKeys());
        verifyButton.setDisable(busy || !hasKeys());
        statusLabel.setText(message);
    }

    private String formatKeys() {
        return "Klucz prywatny = " + toHex(keyPair.privateKey().x()) + System.lineSeparator()
                + "Klucz publiczny = " + toHex(keyPair.publicKey().y()) + System.lineSeparator()
                + System.lineSeparator();
    }

    private String toHex(BigInteger value) {
        return value.toString(16);
    }

    private BigInteger fromHex(String value) {
        String normalized = value == null ? "" : value.trim();
        if (normalized.startsWith("0x") || normalized.startsWith("0X")) {
            normalized = normalized.substring(2);
        }
        if (normalized.isBlank()) {
            throw new NumberFormatException("empty");
        }
        return new BigInteger(normalized, 16);
    }
}
